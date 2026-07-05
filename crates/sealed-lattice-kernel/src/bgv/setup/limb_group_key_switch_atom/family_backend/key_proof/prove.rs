use super::*;
use super::columns::*;
use super::constraints::*;

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

    // Round 1: witness columns plus the carry-range multiplicity columns.
    let base_coefficients = build_base_columns(
        parameters,
        &trace_domain,
        ring_degree,
        secret,
        digits,
        proof_parameters.mask_degree,
        salt_seed,
    )?;
    let base_codewords = base_coefficients
        .iter()
        .map(|c| coset_evaluate_coefficients(&coset_domain, &offset, c))
        .collect::<Vec<_>>();
    let base_commitment = ColumnCommitment::commit(base_codewords, salt_seed)?;

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_digest("key-base-root", &base_commitment.root());
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let lookup_challenge = transcript.challenge_field_elements(parameters, "key-lookup-mu", 1);
    let mu = lookup_challenge[0];

    // Round 2: the logUp fraction columns, which depend on `mu`. The lookup and
    // table terminals are computed here and bound into the transcript.
    let multiplicity_values = carry_multiplicity_values(parameters, ring_degree, digits);
    let aux = build_aux_columns(
        parameters,
        &trace_domain,
        ring_degree,
        digits,
        &multiplicity_values,
        &mu,
        proof_parameters.mask_degree,
        salt_seed,
    )?;
    let aux_codewords = aux
        .coefficients
        .iter()
        .map(|c| coset_evaluate_coefficients(&coset_domain, &offset, c))
        .collect::<Vec<_>>();
    let aux_commitment = ColumnCommitment::commit(aux_codewords, salt_seed)?;
    transcript.absorb_digest("key-aux-root", &aux_commitment.root());
    transcript.absorb_field_elements("key-lookup-terminal", &[aux.lookup_terminal]);
    transcript.absorb_field_elements("key-table-terminals", &aux.table_terminals);

    // Batching challenges: one for the lookup terminal, one per table terminal,
    // folded into the single sumcheck; and the support-constraint weights.
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

    // Sumcheck: f = Ls*S + sum_j (Le_j*E_j + Lc_j*C_j) plus the batched logUp
    // fraction sums, whose target folds in the committed terminals.
    let ls = trace_domain.interpolate(&forms.secret);
    let mut f = polynomial::multiply_via_ntt(parameters, &ls, &base_coefficients[COLUMN_SECRET]);
    for digit in 0..digit_count {
        let le = trace_domain.interpolate(&forms.error_by_digit[digit]);
        let lc = trace_domain.interpolate(&forms.carry_by_digit[digit]);
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::multiply_via_ntt(
                parameters,
                &le,
                &base_coefficients[digit_column(digit, DIGIT_ERROR)],
            ),
        );
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::multiply_via_ntt(
                parameters,
                &lc,
                &base_coefficients[digit_column(digit, DIGIT_CARRY)],
            ),
        );
    }
    let lookup_weight = sum_batch[0];
    for digit in 0..digit_count {
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(
                parameters,
                &aux.coefficients[aux_lookup_column(digit)],
                &lookup_weight,
            ),
        );
    }
    for table_index in 0..table_count {
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(
                parameters,
                &aux.coefficients[aux_table_fraction_column(digit_count, table_index)],
                &sum_batch[1 + table_index],
            ),
        );
    }
    let mut target = parameters.add(
        &forms.target,
        &parameters.multiply(&lookup_weight, &aux.lookup_terminal),
    );
    for table_index in 0..table_count {
        target = parameters.add(
            &target,
            &parameters.multiply(&sum_batch[1 + table_index], &aux.table_terminals[table_index]),
        );
    }

    let vanishing = vanishing_polynomial(parameters, layout.trace_size);
    let q_sc = polynomial::divide_by_vanishing(parameters, &f, layout.trace_size);
    let mut remainder = polynomial::subtract(
        parameters,
        &f,
        &polynomial::multiply_via_ntt(parameters, &q_sc, &vanishing),
    );
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

    // Support: V = sum alpha_i constraint_i, vanishing on H (ternary, eta-2, and
    // the logUp fraction pins).
    let table_polynomials = table_value_polynomials(parameters, &trace_domain, ring_degree);
    let constraints = support_constraints(
        parameters,
        ring_degree,
        digit_count,
        &base_coefficients,
        &aux.coefficients,
        &table_polynomials,
        &mu,
    );
    let mut v = vec![parameters.zero()];
    for (weight, constraint) in alpha.iter().zip(constraints.iter()) {
        v = polynomial::add(
            parameters,
            &v,
            &polynomial::scale(parameters, constraint, weight),
        );
    }
    let q_support = polynomial::divide_by_vanishing(parameters, &v, layout.trace_size);
    let mut support_remainder = polynomial::subtract(
        parameters,
        &v,
        &polynomial::multiply_via_ntt(parameters, &q_support, &vanishing),
    );
    polynomial::trim(&mut support_remainder);
    if support_remainder
        .iter()
        .any(|c| c.iter().any(|limb| *limb != 0))
    {
        return Err(invalid_key("support constraints do not vanish on H"));
    }

    // Round 3: quotients.
    let mut quotient_coefficients = vec![Vec::new(); QUOTIENT_COLUMN_COUNT];
    quotient_coefficients[QUOTIENT_SUMCHECK] = q_sc;
    quotient_coefficients[QUOTIENT_G] = g;
    quotient_coefficients[QUOTIENT_SUPPORT] = q_support;
    let quotient_codewords = quotient_coefficients
        .iter()
        .map(|c| coset_evaluate_coefficients(&coset_domain, &offset, c))
        .collect::<Vec<_>>();
    let quotient_commitment = ColumnCommitment::commit(quotient_codewords.clone(), salt_seed)?;
    transcript.absorb_digest("key-quotient-root", &quotient_commitment.root());

    let base_count = base_commitment.column_count();
    let aux_count = aux_commitment.column_count();
    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + aux_count + QUOTIENT_COLUMN_COUNT,
    );

    // Combination codeword: weighted sum of every committed column's codeword,
    // across all three commitment rounds.
    let mut combination = vec![parameters.zero(); layout.coset_size];
    let mut weight_index = 0;
    for column in 0..base_count {
        let weight = weights[weight_index];
        weight_index += 1;
        for (slot, index) in combination.iter_mut().zip(0..layout.coset_size) {
            *slot = parameters.add(
                slot,
                &parameters.multiply(&weight, &base_commitment.value(column, index)),
            );
        }
    }
    for column in 0..aux_count {
        let weight = weights[weight_index];
        weight_index += 1;
        for (slot, index) in combination.iter_mut().zip(0..layout.coset_size) {
            *slot = parameters.add(
                slot,
                &parameters.multiply(&weight, &aux_commitment.value(column, index)),
            );
        }
    }
    for (quotient, codeword) in quotient_codewords.iter().enumerate() {
        let weight = weights[base_count + aux_count + quotient];
        for (slot, value) in combination.iter_mut().zip(codeword.iter()) {
            *slot = parameters.add(slot, &parameters.multiply(&weight, value));
        }
    }

    let fri_commitment = fri_commit(
        parameters,
        &mut transcript,
        &combination,
        &offset,
        salt_seed,
    )?;
    let query_positions = transcript.challenge_positions(
        "key-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    let fri = fri_answer(&fri_commitment, &query_positions);

    let half = layout.coset_size / 2;
    let mut open_indices = Vec::with_capacity(query_positions.len() * 2);
    for &position in &query_positions {
        let folded = position % half;
        open_indices.push(folded);
        open_indices.push(folded + half);
    }
    let base_opening = base_commitment.open(&open_indices);
    let aux_opening = aux_commitment.open(&open_indices);
    let quotient_opening = quotient_commitment.open(&open_indices);

    Ok(KeyFriProof {
        base_root: base_commitment.root(),
        aux_root: aux_commitment.root(),
        quotient_root: quotient_commitment.root(),
        fri,
        base_opening,
        aux_opening,
        quotient_opening,
        lookup_terminal: aux.lookup_terminal,
        table_terminals: aux.table_terminals,
    })
}

